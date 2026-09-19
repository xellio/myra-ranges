package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseCIDR(t *testing.T) {
	cases := map[string]string{
		"185.85.3.0/24":            "185.85.3.0/24",
		"185.85.3.7/24":            "185.85.3.0/24", // host bits masked
		"5.9.89.19":                "5.9.89.19/32",
		"5.9.89.19/32":             "5.9.89.19/32",
		" 2a01:4a0::/32 ":          "2a01:4a0::/32",
		"2a01:4f8:162:1346::2/128": "2a01:4f8:162:1346::2/128",
	}
	for in, want := range cases {
		p, err := parseCIDR(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if p.String() != want {
			t.Errorf("%q -> %s, want %s", in, p, want)
		}
	}
	for _, bad := range []string{"", "not-an-ip", "300.1.1.1/24", "10.0.0.0/33"} {
		if _, err := parseCIDR(bad); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
}

func TestCanonicalRule(t *testing.T) {
	cases := map[string]string{
		"allow 1.2.3.4/32;":      "allow 1.2.3.4;",
		"allow 1.2.3.4;":         "allow 1.2.3.4;",
		"allow  10.0.0.7/8 ;":    "allow 10.0.0.0/8;",
		"allow 2a02:cb43::/32;":  "allow 2a02:cb43::/32;",
		"allow 2001:db8::1/128;": "allow 2001:db8::1;",
		"deny all;":              "deny all;",
		"deny\tall;":             "deny all;",
		"allow not-an-ip;":       "allow not-an-ip;",
		"satisfy any;":           "satisfy any;",
	}
	for in, want := range cases {
		if got := canonicalRule(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

func TestRenderAndDiff(t *testing.T) {
	cfg := &configuration{ExtraAllow: []string{"127.0.0.1", "::1", "192.168.1.0/24"}}
	ranges := []string{"45.91.156.0/22", "5.9.89.19/32", "2a02:cb43::/32"}
	out := string(render(cfg, ranges))

	for _, want := range []string{
		"allow 127.0.0.1;", "allow ::1;", "allow 192.168.1.0/24;",
		"allow 45.91.156.0/22;", "allow 5.9.89.19;", "allow 2a02:cb43::/32;",
		"deny all;", "# 3 Myra ranges.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered snippet lacks %q:\n%s", want, out)
		}
	}
	if !strings.HasSuffix(strings.TrimSpace(out), "deny all;") {
		t.Errorf("deny all must be last")
	}

	// same content, different comments/order/spelling (/32 vs bare host) -> no diff
	old := "# hand-written\nallow 5.9.89.19/32;\nallow 192.168.1.0/24;\nallow ::1;\nallow 127.0.0.1;\nallow 2a02:cb43::/32;   # trailing comment\nallow 45.91.156.0/22;\ndeny all;\n"
	added, removed := diffAllows([]byte(old), []byte(out))
	if len(added) != 0 || len(removed) != 0 {
		t.Errorf("unexpected diff: +%v -%v", added, removed)
	}
	if string(normalize([]byte(old))) != string(normalize([]byte(out))) {
		t.Errorf("normalize should be equal")
	}

	// a range disappears and a new one appears
	newer := render(cfg, []string{"45.91.156.0/22", "80.90.0.0/20", "2a02:cb43::/32"})
	added, removed = diffAllows([]byte(out), newer)
	if len(added) != 1 || added[0] != "allow 80.90.0.0/20;" {
		t.Errorf("added = %v", added)
	}
	if len(removed) != 1 || removed[0] != "allow 5.9.89.19;" {
		t.Errorf("removed = %v", removed)
	}
}

func TestApplyRollsBackOnFailedTest(t *testing.T) {
	dir := t.TempDir()
	snippet := filepath.Join(dir, "myra-only.conf")
	current := []byte("allow 1.2.3.4;\ndeny all;\n")
	if err := os.WriteFile(snippet, current, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &configuration{Snippet: snippet, NginxTest: "false", NginxReload: "true"}
	err := apply(cfg, current, []byte("allow 5.6.7.8;\ndeny all;\n"))
	if err == nil {
		t.Fatal("expected error from failing nginx test")
	}
	got, _ := os.ReadFile(snippet)
	if string(got) != string(current) {
		t.Errorf("snippet not restored after failed test: %q", got)
	}
	prev, _ := os.ReadFile(snippet + ".prev")
	if string(prev) != string(current) {
		t.Errorf(".prev not written: %q", prev)
	}
}

func TestApplySuccess(t *testing.T) {
	dir := t.TempDir()
	snippet := filepath.Join(dir, "myra-only.conf")
	cfg := &configuration{Snippet: snippet, NginxTest: "true", NginxReload: "true"}
	rendered := []byte("allow 5.6.7.8;\ndeny all;\n")
	if err := apply(cfg, nil, rendered); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(snippet)
	if string(got) != string(rendered) {
		t.Errorf("snippet = %q", got)
	}
	if _, err := os.Stat(snippet + ".tmp"); err == nil {
		t.Errorf(".tmp left behind")
	}
}
