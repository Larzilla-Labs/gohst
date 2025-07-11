package utils

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// EmptyStruct is good for coalescing variatic optional parameters in func calls
func StructSafe(data ...interface{}) interface{} {
    if len(data) > 0 {
        if s, ok := data[0].([]interface{}); ok && len(s) > 0 {
            return s[0]
        }
        return data[0]
    }

    return struct{}{}
}

// Make sure struct is not nil where it is needed
func StructNil(data interface{}) interface{} {
    if data == nil {
        return struct{}{}
    }

    return data
}

// StringOr returns the string representation of val if it's not nil,
// otherwise returns the default value
func StringOr(val any, defaultVal string) string {
    if val == nil {
        return defaultVal
    }

    // Convert the value to string
    return fmt.Sprint(val)
}

// GenerateToken generates a new CSRF token.
func GenerateCSRF() (string, error) {
    b := make([]byte, 32)
    _, err := rand.Read(b)
    if err != nil {
        return "", err
    }
    return base64.StdEncoding.EncodeToString(b), nil
}
