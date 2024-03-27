//
// Miscellaneous formatting utilities
//

package format

import (
	"regexp"
	"strconv"
)

//
// Split string by delimiter, filter out empties
//

var splitStringRe = regexp.MustCompile(`\s*[,\s]+\s*`)

func SplitStringByDelimiter(input string) []string {
	result := []string{}
	split := splitStringRe.Split(input, -1)

	for _, s := range split {
		if s != "" {
			result = append(result, s)
		}
	}

	return result
}

//
// Split string of numbers by delimiter, convert to int
//

func SplitIntsByDelimiter(input string) ([]int, error) {
	result := []int{}
	split := SplitStringByDelimiter(input)

	for _, s := range split {
		i, err := strconv.Atoi(s)
		if err != nil {
			return nil, err
		}

		result = append(result, i)
	}

	return result, nil
}
