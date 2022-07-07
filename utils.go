package pe

import (
	"math"
	"strings"
)

type EntropyCalculator struct {
	size        int
	frequencies [256]uint64
}

func (e *EntropyCalculator) Write(p []byte) (n int, err error) {
	e.size += len(p)
	for _, v := range p {
		e.frequencies[v]++
	}
	return len(p), err
}

func (e *EntropyCalculator) Sum() (entropy float64) {
	if e.size == 0 {
		return
	}

	for _, p := range e.frequencies {
		if p > 0 {
			freq := float64(p) / float64(e.size)
			entropy += freq * math.Log2(freq)
		}
	}
	return -entropy
}

func GetResourceTypeName(resourceType ResourceDirectoryEntry) string {
	if resourceType.Name != "" {
		return resourceType.Name
	} else {
		return ResourceType(resourceType.Struct.Name).String()
	}
}

// stringInSlice checks weather a string exists in a slice of strings.
func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func Max(x, y uint32) uint32 {
	if x < y {
		return y
	}
	return x
}
func intInSlice(a uint32, list []uint32) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func Min(values []uint32) uint32 {
	min := values[0]
	for _, v := range values {
		if v < min {
			min = v
		}
	}
	return min
}

func IsValidFunctionName(functionName string) bool {
	alphabet := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	numerals := "0123456789"
	special := "_?@$()<>"
	charset := alphabet + numerals + special
	for _, c := range charset {
		if !strings.Contains(charset, string(c)) {
			return false
		}
	}
	return true
}

func IsValidDosFilename(filename string) bool {
	alphabet := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	numerals := "0123456789"
	special := "!#$%&'()-@^_`{}~+,.;=[]\\/"
	charset := alphabet + numerals + special
	for _, c := range filename {
		if !strings.Contains(charset, string(c)) {
			return false
		}
	}
	return true
}
