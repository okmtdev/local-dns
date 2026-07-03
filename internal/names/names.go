// Package names provides validation and normalization helpers for
// DNS host names and MAC addresses shared across the project.
package names

import (
	"fmt"
	"net"
	"strings"
)

// ValidateLabels validates a relative DNS name such as "nas" or
// "printer.office". Each dot-separated label must follow hostname rules
// (letters, digits, hyphen; no leading/trailing hyphen; 63 bytes max).
// The caller is expected to lowercase the name first via Normalize.
func ValidateLabels(name string) error {
	if name == "" {
		return fmt.Errorf("ホスト名が空です")
	}
	if len(name) > 200 {
		return fmt.Errorf("ホスト名が長すぎます (200文字以内)")
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			return fmt.Errorf("ホスト名 %q にラベルの抜け (連続したドットなど) があります", name)
		}
		if len(label) > 63 {
			return fmt.Errorf("ラベル %q が長すぎます (63文字以内)", label)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			ok := c == '-' || ('a' <= c && c <= 'z') || ('0' <= c && c <= '9')
			if !ok {
				return fmt.Errorf("ホスト名 %q に使用できない文字が含まれています (英小文字・数字・ハイフンのみ)", name)
			}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("ラベル %q の先頭・末尾にハイフンは使えません", label)
		}
	}
	return nil
}

// Normalize lowercases a host name and strips surrounding whitespace
// and dots. It does not validate.
func Normalize(name string) string {
	return strings.Trim(strings.ToLower(strings.TrimSpace(name)), ".")
}

// NormalizeMAC parses a MAC address in any common notation and returns
// the canonical lowercase colon-separated form ("aa:bb:cc:dd:ee:ff").
func NormalizeMAC(s string) (string, error) {
	hw, err := net.ParseMAC(strings.TrimSpace(s))
	if err != nil || len(hw) != 6 {
		return "", fmt.Errorf("MACアドレスの形式が不正です: %q", s)
	}
	return hw.String(), nil
}
