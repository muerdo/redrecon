package target

import (
	"testing"
)

func TestGetRootDomain_CTF(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// CTF TLDs - devem ser preservados
		{"HTB domain", "dev.target.htb", "dev.target.htb"},
		{"THM domain", "staging.room.thm", "staging.room.thm"},
		{"CTF domain", "app.challenge.ctf", "app.challenge.ctf"},
		{"Local domain", "api.service.local", "api.service.local"},
		{"Lab domain", "test.lab.box", "test.lab.box"},

		// Subdomínios importantes - devem ser preservados
		{"Staging subdomain", "staging.example.com", "staging.example.com"},
		{"Dev subdomain", "dev.example.com", "dev.example.com"},
		{"Test subdomain", "test.example.com", "test.example.com"},
		{"API subdomain", "api.example.com", "api.example.com"},
		{"Admin subdomain", "admin.example.com", "admin.example.com"},
		{"Portal subdomain", "portal.example.com", "portal.example.com"},
		{"App subdomain", "app.example.com", "app.example.com"},
		{"Beta subdomain", "beta.example.com", "beta.example.com"},
		{"Demo subdomain", "demo.example.com", "demo.example.com"},

		// IPs - devem ser preservados
		{"IPv4 address", "192.168.1.1", "192.168.1.1"},
		{"IPv6 address", "2001:db8::1", "2001:db8::1"},

		// Domínios públicos normais - devem usar publicsuffix
		{"Normal domain", "example.com", "example.com"},
		{"Subdomain of public", "www.example.com", "example.com"},
		{"Deep subdomain public", "mail.subdomain.example.com", "example.com"},
		{"UK domain", "example.co.uk", "example.co.uk"},
		{"Subdomain UK", "www.example.co.uk", "example.co.uk"},

		// URLs com protocolo
		{"HTTP URL with staging", "http://staging.example.com", "staging.example.com"},
		{"HTTPS URL with dev", "https://dev.target.htb", "dev.target.htb"},
		{"URL with port", "http://api.example.com:8080", "api.example.com"},

		// Edge cases
		{"Single word", "localhost", "localhost"},
		{"Empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetRootDomain(tt.input)
			if result != tt.expected {
				t.Errorf("GetRootDomain(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestGetRootDomain_Consistency(t *testing.T) {
	// Testa que múltiplas chamadas retornam o mesmo resultado
	target := "staging.example.htb"
	first := GetRootDomain(target)
	second := GetRootDomain(target)

	if first != second {
		t.Errorf("GetRootDomain is not consistent: first=%q, second=%q", first, second)
	}
}

func TestIsLocalOrCTFDomain(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		expected bool
	}{
		// Should return true
		{"HTB domain", "target.htb", true},
		{"THM domain", "room.thm", true},
		{"CTF domain", "challenge.ctf", true},
		{"Local domain", "service.local", true},
		{"Lab domain", "test.lab", true},
		{"Staging prefix", "staging.example.com", true},
		{"Dev prefix", "dev.example.com", true},
		{"API prefix", "api.example.com", true},
		{"IPv4", "192.168.1.1", true},

		// Should return false
		{"Normal domain", "example.com", false},
		{"WWW subdomain", "www.example.com", false},
		{"Mail subdomain", "mail.example.com", false},
		{"Random subdomain", "random.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isLocalOrCTFDomain(tt.domain)
			if result != tt.expected {
				t.Errorf("isLocalOrCTFDomain(%q) = %v, expected %v", tt.domain, result, tt.expected)
			}
		})
	}
}

func TestGetCommonTargetFromInput(t *testing.T) {
	// This test requires file I/O, so we'll create a temporary file
	// For now, just test the basic logic
	t.Skip("Requires file I/O setup")
}
