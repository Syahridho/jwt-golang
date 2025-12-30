package utils

import (
	"crypto/rand"
	"encoding/hex"
)

// GenerateRandomToken generates a random token for password reset
func GenerateRandomToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
