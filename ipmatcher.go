package firewall

import (
	"log"
	"net"
	"strconv"
	"strings"
)

type ipMatcher struct {
	ip      net.IP
	network *net.IPNet
}

func newIPMatcher(rule string) *ipMatcher {
	s := strings.Split(rule, "/")
	if len(s) == 1 {
		return &ipMatcher{ip: parseIP(s[0])}
	}

	if len(s) == 2 {
		m, err := strconv.Atoi(s[1])
		if err != nil {
			log.Fatalf("parse ip mask %q failed: %v", s[1], err)
		}
		return &ipMatcher{
			network: &net.IPNet{
				IP:   parseIP(s[0]),
				Mask: net.CIDRMask(m, 32),
			},
		}
	}

	log.Fatalf("parse whitelist rule %q failed", rule)
	return nil
}

func (s *ipMatcher) match(ip net.IP) bool {
	if s.ip != nil {
		return s.ip.Equal(ip)
	}
	if s.network != nil {
		return s.network.Contains(ip)
	}
	// Not reach
	return false
}

func parseIP(s string) net.IP {
	// This is safe to crash, as the ip is from config
	ip := net.ParseIP(s)
	if ip == nil {
		log.Fatalf("net.ParseIP(%q) failed", s)
	}

	ip = ip.To4()
	if ip == nil {
		log.Fatalf("%q is not ipv4", s)
	}

	return ip
}
