package firewall

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/charleshuang3/firewall/ipgeo"
)

// MockIFirewall is a mock implementation of IFirewall for testing.
type MockIFirewall struct {
	BannedIPs []string
}

func (m *MockIFirewall) BanIP(ip string, timeoutInMinute int) {
	m.BannedIPs = append(m.BannedIPs, ip)
}

// MockILogger is a mock implementation of ILogger for testing.
type MockILogger struct {
	Logs []LogEntry
	Wg   sync.WaitGroup
}

type LogEntry struct {
	IP        string
	JailUntil time.Time
	Reasons   []string
	Action    string
	Geo       *ipgeo.IPGeo
}

func (m *MockILogger) Log(ip string, jailUntil time.Time, reasons []string, action string, geo *ipgeo.IPGeo) {
	m.Logs = append(m.Logs, LogEntry{
		IP:        ip,
		JailUntil: jailUntil,
		Reasons:   reasons,
		Action:    action,
		Geo:       geo,
	})
	m.Wg.Done()
}

func TestBanIP(t *testing.T) {
	tests := []struct {
		name            string
		ip              string
		timeoutInMinute int
		reason          string
		whiteList       []string
		expectedBanned  bool
		expectedLog     *LogEntry // Changed to pointer
	}{
		{
			name:            "Ban non-whitelisted IP",
			ip:              "192.168.1.1",
			timeoutInMinute: 10,
			reason:          "Too many failed logins",
			whiteList:       []string{},
			expectedBanned:  true,
			expectedLog: &LogEntry{ // Changed to pointer
				IP:      "192.168.1.1",
				Reasons: []string{"Too many failed logins"},
				Action:  "ban",
				Geo:     nil, // Mock IPGeo is nil
			},
		},
		{
			name:            "Do not ban whitelisted IP",
			ip:              "192.168.1.2",
			timeoutInMinute: 10,
			reason:          "Too many failed logins",
			whiteList:       []string{"192.168.1.2"},
			expectedBanned:  false,
			// expectedLog is intentionally omitted as no log is expected.
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFW := &MockIFirewall{}
			mockLogger := &MockILogger{}
			fw := New(tt.whiteList, mockFW, mockLogger, nil, ForgivableError{}) // ipGeo and forgivableError are not used in BanIP directly

			if tt.expectedLog != nil { // If we expect a log
				mockLogger.Wg.Add(1)
				fw.BanIP(tt.ip, tt.timeoutInMinute, tt.reason)
				mockLogger.Wg.Wait()

				assert.Len(t, mockLogger.Logs, 1)
				logEntry := mockLogger.Logs[0]
				assert.Equal(t, tt.expectedLog.IP, logEntry.IP)
				assert.Equal(t, tt.expectedLog.Reasons, logEntry.Reasons)
				assert.Equal(t, tt.expectedLog.Action, logEntry.Action)
				// Geo and JailUntil are not checked precisely here
			} else { // If we do not expect a log (whitelisted IP or other no-log scenarios)
				fw.BanIP(tt.ip, tt.timeoutInMinute, tt.reason)
				assert.Empty(t, mockLogger.Logs)
			}

			if tt.expectedBanned {
				assert.Equal(t, []string{tt.ip}, mockFW.BannedIPs)
			} else {
				// For "Do not ban whitelisted IP", BannedIPs should be empty.
				// For other potential future test cases that might not ban but also not be whitelisted,
				// NotContains might be more appropriate if BannedIPs could have other entries.
				// Given current tests, Empty is fine for the whitelisted case.
				// Sticking to NotContains as it was, which is also safe.
				assert.NotContains(t, mockFW.BannedIPs, tt.ip)
			}
		})
	}
}

func TestLogIPError(t *testing.T) {
	tests := []struct {
		name              string
		ip                string
		reason            string
		forgivable        ForgivableError
		errorCount        int // Number of times to call LogIPError
		whiteList         []string
		expectedBanned    bool
		expectedLogAction string
		expectLog         bool
	}{
		{
			name:              "Log error at threshold",
			ip:                "192.168.1.1",
			reason:            "Invalid password",
			forgivable:        ForgivableError{Duration: time.Minute, Count: 2, BanInMinute: 5},
			errorCount:        2,
			whiteList:         []string{},
			expectedBanned:    false,
			expectedLogAction: "count error",
			expectLog:         true,
		},
		{
			name:              "Log error above threshold, should ban",
			ip:                "192.168.1.1",
			reason:            "Invalid password",
			forgivable:        ForgivableError{Duration: time.Minute, Count: 2, BanInMinute: 5},
			errorCount:        3,
			whiteList:         []string{},
			expectedBanned:    true,
			expectedLogAction: "ban",
			expectLog:         true,
		},
		{
			name:              "Log error above threshold + 1, should not be double ban",
			ip:                "192.168.1.1",
			reason:            "Invalid password",
			forgivable:        ForgivableError{Duration: time.Minute, Count: 2, BanInMinute: 5},
			errorCount:        4,
			whiteList:         []string{},
			expectedBanned:    true,
			expectedLogAction: "banned",
			expectLog:         true,
		},
		{
			name:              "Log error for whitelisted IP",
			ip:                "192.168.1.2",
			reason:            "Invalid password",
			forgivable:        ForgivableError{Duration: time.Minute, Count: 3, BanInMinute: 5},
			errorCount:        5, // Should not matter for whitelisted
			whiteList:         []string{"192.168.1.2"},
			expectedBanned:    false,
			expectedLogAction: "whitelisted",
			expectLog:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFW := &MockIFirewall{}
			mockLogger := &MockILogger{}
			fw := New(tt.whiteList, mockFW, mockLogger, nil, tt.forgivable) // ipGeo is not used in LogIPError directly

			if tt.expectLog { // Use the new field from the test struct
				mockLogger.Wg.Add(tt.errorCount)
			}

			for i := 0; i < tt.errorCount; i++ {
				fw.LogIPError(tt.ip, tt.reason)
			}

			if tt.expectLog { // Use the new field from the test struct
				mockLogger.Wg.Wait()
				assert.Len(t, mockLogger.Logs, tt.errorCount)
				assert.NotEmpty(t, mockLogger.Logs) // Should be true if errorCount > 0
				lastLogEntry := mockLogger.Logs[len(mockLogger.Logs)-1]
				assert.Equal(t, tt.expectedLogAction, lastLogEntry.Action)
			} else {
				assert.Empty(t, mockLogger.Logs)
			}

			if tt.expectedBanned {
				assert.Equal(t, []string{tt.ip}, mockFW.BannedIPs)
			} else {
				assert.NotContains(t, mockFW.BannedIPs, tt.ip)
			}
		})
	}
}
