package format

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEc2InstanceIdFromArn(t *testing.T) {
	result := Ec2InstanceIdFromArn("arn:aws:ec2:us-west-1:1234567890:instance/i-1234567890abcdef")
	assert.Equal(t, "i-1234567890abcdef", result)
}

func TestEc2InstanceIdFromArnErr(t *testing.T) {
	arn := "invalid-arn"
	result := Ec2InstanceIdFromArn(arn)
	assert.Equal(t, arn, result)
}

func TestEcsTaskArnToClusterArn(t *testing.T) {
	result := EcsTaskArnToClusterArn("arn:aws:ecs:us-west-1:1234567890:task/my-cluster/3f8fae2a-33ce-4c19-ba06-3f3009a7c33a")
	assert.Equal(t, "arn:aws:ecs:us-west-1:1234567890:cluster/my-cluster", result)
}

func TestEcsTaskArnToClusterArnErr(t *testing.T) {
	arn := "invalid-arn"
	result := EcsTaskArnToClusterArn(arn)
	assert.Equal(t, arn, result)
}
