package names

import (
	"strings"
	"testing"
)

func TestValidateLabels(t *testing.T) {
	valid := []string{"nas", "living-tv", "a", "a1", "1a", "nas.storage", "x0-y1.z2"}
	for _, v := range valid {
		if err := ValidateLabels(v); err != nil {
			t.Errorf("ValidateLabels(%q) = %v, want nil", v, err)
		}
	}
	invalid := []string{
		"", ".", "a..b", "-nas", "nas-", "na_s", "NAS", "日本語",
		"a.-b", strings.Repeat("a", 64), strings.Repeat("a.", 101) + "a",
	}
	for _, v := range invalid {
		if err := ValidateLabels(v); err == nil {
			t.Errorf("ValidateLabels(%q) = nil, want error", v)
		}
	}
}

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"  NAS.  ": "nas",
		"Nas.Home": "nas.home",
		".":        "",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeMAC(t *testing.T) {
	got, err := NormalizeMAC("AA-BB-CC-DD-EE-FF")
	if err != nil || got != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("NormalizeMAC dash form = %q, %v", got, err)
	}
	got, err = NormalizeMAC("aa:bb:cc:dd:ee:ff")
	if err != nil || got != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("NormalizeMAC colon form = %q, %v", got, err)
	}
	for _, bad := range []string{"", "nonsense", "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:ff:00:11"} {
		if _, err := NormalizeMAC(bad); err == nil {
			t.Errorf("NormalizeMAC(%q) = nil error, want error", bad)
		}
	}
}
