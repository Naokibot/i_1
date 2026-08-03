package main

import (
	"strings"
	"testing"
)

func TestValidateListenSecurity(t *testing.T) {
	strongToken := strings.Repeat("a", minimumAPITokenLength)
	tests := []struct {
		name    string
		address string
		token   string
		wantErr bool
	}{
		{name: "IPv4 loopback", address: "127.0.0.1:8080"},
		{name: "IPv6 loopback", address: "[::1]:8080"},
		{name: "localhost", address: "localhost:8080"},
		{name: "all interfaces without token", address: ":8080", wantErr: true},
		{name: "IPv4 all interfaces without token", address: "0.0.0.0:8080", wantErr: true},
		{name: "remote with short token", address: "192.0.2.10:8080", token: "short", wantErr: true},
		{name: "remote with strong token", address: "192.0.2.10:8080", token: strongToken},
		{name: "invalid address", address: "8080", token: strongToken, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateListenSecurity(tt.address, tt.token)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error=%v wantErr=%v", err, tt.wantErr)
			}
		})
	}
}
