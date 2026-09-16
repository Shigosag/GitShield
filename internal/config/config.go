package config

import (
	"os"
	"strconv"
)

type Config struct {
	EntropyThreshold float64
	DefaultFailOn    string
}

func LoadConfig() *Config {
	threshold := 4.5
	if raw := os.Getenv("GITSHIELD_ENTROPY_THRESHOLD"); raw != "" {
		if val, err := strconv.ParseFloat(raw, 64); err == nil {
			threshold = val
		}
	}

	failOn := "HIGH"
	if raw := os.Getenv("GITSHIELD_FAIL_ON"); raw != "" {
		failOn = raw
	}

	return &Config{
		EntropyThreshold: threshold,
		DefaultFailOn:    failOn,
	}
}