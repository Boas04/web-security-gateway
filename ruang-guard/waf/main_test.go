package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestCRS(t *testing.T) {
	waf, err := newWAF()
	if err != nil {
		t.Fatal(err)
	}
	t.Run("malformed-query-fails-closed", func(t *testing.T) {
		result, err := inspect(waf, envelope{Method: "GET", URI: "/api/documents?q=x;y=%3Cscript%3E", Headers: map[string]string{"Host": "localhost"}})
		if err == nil || result.Allowed {
			t.Fatal("partially parsed query must not be allowed")
		}
	})
	for _, tc := range []struct {
		name, uri, body string
		allowed         bool
	}{
		{"normal", "/api/documents?q=privasi", "", true},
		{"sql", "/api/documents?q=1%27%20OR%20%271%27%3D%271%27%20--", "", false},
		{"xss", "/api/documents?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "", false},
        {"path-traversal", "/api/documents?file=..%2F..%2F..%2F..%2Ffictional-secret.txt", "", false},
        {"double-encoded-traversal", "/api/documents?file=%252e%252e%252f%252e%252e%252ffictional-secret.txt", "", false},
		{"normal-json", "/api/complaints", `{"title":"Lampu taman fiktif","category":"Lingkungan","location":"Kota Imaji","description":"Lampu taman rekaan tidak menyala dalam simulasi malam ini."}`, true},
		{"xss-json", "/api/complaints", `{"description":"<script>alert(1)</script>"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			method := "GET"
			if tc.body != "" {
				method = "POST"
			}
			result, err := inspect(waf, envelope{Method: method, URI: tc.uri, Body: base64.StdEncoding.EncodeToString([]byte(tc.body)), Client: "192.168.1.20", Headers: map[string]string{"Host": "localhost:8090", "User-Agent": "RuangGuardLab/1.0", "Accept": "application/json", "Content-Type": "application/json"}})
			if err != nil {
				t.Fatal(err)
			}
			if result.Allowed != tc.allowed {
				t.Fatalf("allowed=%v rules=%v", result.Allowed, result.Rules)
			}
			if !tc.allowed && len(result.Rules) == 0 {
				t.Fatal("missing CRS rule IDs")
			}
		})
	}
	t.Run("oversized", func(t *testing.T) {
		result, _ := inspect(waf, envelope{Method: "POST", URI: "/api/complaints", Body: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 17000))), Headers: map[string]string{"Host": "localhost", "Content-Type": "application/json"}})
		if result.Allowed {
			t.Fatal("oversized body allowed")
		}
	})
}
