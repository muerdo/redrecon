package utils

import "time"

// GetCurrentTimestamp returns the current time as a formatted string (YYYYMMDDHHMMSS).
func GetCurrentTimestamp() string {
	return time.Now().Format("20060102150405")
}