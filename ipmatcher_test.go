package firewall

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewIPMatcher(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectedIP  net.IP
		expectedNet *net.IPNet
	}{
		{
			name:       "single IP",
			rule:       "192.168.1.1",
			expectedIP: net.ParseIP("192.168.1.1").To4(),
		},
		{
			name: "CIDR notation",
			rule: "10.0.0.0/8",
			expectedNet: &net.IPNet{
				IP:   net.ParseIP("10.0.0.0").To4(),
				Mask: net.CIDRMask(8, 32),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := newIPMatcher(tt.rule)

			if tt.expectedIP != nil {
				assert.NotNil(t, matcher.ip, "newIPMatcher(%q) expected ip not to be nil", tt.rule)
				assert.True(t, matcher.ip.Equal(tt.expectedIP), "newIPMatcher(%q) ip got %v, want %v", tt.rule, matcher.ip, tt.expectedIP)
				assert.Nil(t, matcher.network, "newIPMatcher(%q) expected network to be nil, got %v", tt.rule, matcher.network)
			}

			if tt.expectedNet != nil {
				assert.NotNil(t, matcher.network, "newIPMatcher(%q) expected network not to be nil", tt.rule)
				assert.True(t, matcher.network.IP.Equal(tt.expectedNet.IP), "newIPMatcher(%q) network.IP got %v, want %v", tt.rule, matcher.network.IP, tt.expectedNet.IP)
				assert.Equal(t, matcher.network.Mask.String(), tt.expectedNet.Mask.String(), "newIPMatcher(%q) network.Mask got %v, want %v", tt.rule, matcher.network.Mask, tt.expectedNet.Mask)
				assert.Nil(t, matcher.ip, "newIPMatcher(%q) expected ip to be nil, got %v", tt.rule, matcher.ip)
			}
		})
	}
}

func TestIPMatcher_Match(t *testing.T) {
	tests := []struct {
		name      string
		rule      string
		ipToMatch string
		expected  bool
	}{
		{
			name:      "single IP match",
			rule:      "192.168.1.10",
			ipToMatch: "192.168.1.10",
			expected:  true,
		},
		{
			name:      "single IP no match",
			rule:      "192.168.1.10",
			ipToMatch: "192.168.1.11",
			expected:  false,
		},
		{
			name:      "CIDR match",
			rule:      "10.0.0.0/8",
			ipToMatch: "10.1.2.3",
			expected:  true,
		},
		{
			name:      "CIDR no match",
			rule:      "10.0.0.0/8",
			ipToMatch: "11.0.0.1",
			expected:  false,
		},
		{
			name:      "CIDR match network address",
			rule:      "192.168.1.0/24",
			ipToMatch: "192.168.1.0",
			expected:  true,
		},
		{
			name:      "CIDR match broadcast address",
			rule:      "192.168.1.0/24",
			ipToMatch: "192.168.1.255",
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := newIPMatcher(tt.rule)
			ip := net.ParseIP(tt.ipToMatch)
			if ip == nil {
				t.Fatalf("Invalid IP in test case: %s", tt.ipToMatch)
			}
			assert.Equal(t, tt.expected, matcher.match(ip.To4()), "ipMatcher.match() for rule %q with IP %q", tt.rule, tt.ipToMatch)
		})
	}
}
