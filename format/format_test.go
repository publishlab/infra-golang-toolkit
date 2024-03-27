package format

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSplitStringByDelimiter(t *testing.T) {
	tests := []struct {
		in  string
		out []string
	}{
		{in: "a,b,c", out: []string{"a", "b", "c"}},
		{in: "1 2 3", out: []string{"1", "2", "3"}},
		{in: "x,y z", out: []string{"x", "y", "z"}},
		{in: "foo,bar,baz", out: []string{"foo", "bar", "baz"}},
		{in: "", out: []string{}},
		{in: ",,,", out: []string{}},
	}

	for _, test := range tests {
		result := SplitStringByDelimiter(test.in)
		assert.Equal(t, test.out, result)
	}
}

func TestSplitIntsByDelimiter(t *testing.T) {
	tests := []struct {
		in  string
		out []int
		err interface{}
	}{
		{in: "1,2,3", out: []int{1, 2, 3}},
		{in: "4 5 6", out: []int{4, 5, 6}},
		{in: "7,8 9", out: []int{7, 8, 9}},
		{in: "a b,c", err: &strconv.NumError{}},
		{in: "", out: []int{}},
		{in: ",,,", out: []int{}},
	}

	for _, test := range tests {
		result, err := SplitIntsByDelimiter(test.in)
		assert.Equal(t, test.out, result)
		assert.IsType(t, test.err, err)
	}
}
