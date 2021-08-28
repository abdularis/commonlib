package types

import "strconv"

func StringToUint(str string) uint {
	parsedInt, err := strconv.ParseUint(str, 10, 32)
	if err != nil {
		return 0
	}

	return uint(parsedInt)
}

func StringToInt(str string) int {
	parsedInt, err := strconv.ParseInt(str, 10, 32)
	if err != nil {
		return 0
	}

	return int(parsedInt)
}

func StringToInt64(str string) int64 {
	parsedInt, err := strconv.ParseInt(str, 10, 64)
	if err != nil {
		return 0
	}

	return parsedInt
}

func StringToUint64(str string) uint {
	parsedInt, err := strconv.ParseUint(str, 10, 64)
	if err != nil {
		return 0
	}

	return uint(parsedInt)
}

// CompareUintPtr deep comparison uint pointer
func CompareUintPtr(a *uint, b *uint) bool {
	if a == b {
		return true
	}

	if a != nil {
		if b != nil {
			return *a == *b
		}
		return false
	}
	return false
}
