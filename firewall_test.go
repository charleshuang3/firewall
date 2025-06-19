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
		expectedLog     LogEntry // This field is optional; only provided for cases expecting logs.
	}{
		{
			name:            "Ban non-whitelisted IP",
			ip:              "192.168.1.1",
			timeoutInMinute: 10,
			reason:          "Too many failed logins",
			whiteList:       []string{},
			expectedBanned:  true,
			expectedLog: LogEntry{ // Log is expected for this case
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

			if tt.name == "Do not ban whitelisted IP" {
				fw.BanIP(tt.ip, tt.timeoutInMinute, tt.reason)
				assert.Empty(t, mockLogger.Logs) // Expect no logs for whitelisted IP
			} else { // "Ban non-whitelisted IP" or other cases that expect logs
				mockLogger.Wg.Add(1)
				fw.BanIP(tt.ip, tt.timeoutInMinute, tt.reason)
				mockLogger.Wg.Wait()

				assert.Len(t, mockLogger.Logs, 1)
				logEntry := mockLogger.Logs[0]
				// Assertions for the "Ban non-whitelisted IP" case using tt.expectedLog
				assert.Equal(t, tt.expectedLog.IP, logEntry.IP)
				assert.Equal(t, tt.expectedLog.Reasons, logEntry.Reasons)
				assert.Equal(t, tt.expectedLog.Action, logEntry.Action)
				// Geo and JailUntil are not checked precisely here
			}

			if tt.expectedBanned {
				assert.Equal(t, []string{tt.ip}, mockFW.BannedIPs)
			} else {
				assert.NotContains(t, mockFW.BannedIPs, tt.ip)
			}
			// We don't check JailUntil and Geo precisely due to time dependency and nil geo for the logged case
		})
	}
}

func TestLogIPError(t *testing.T) {
	// Note: The LogEntry struct definition for expectedLog in TestBanIP might need adjustment
	// if it was fully removed. The instructions were to remove the variable `expectedLog`,
	// not necessarily the type from the test struct. Assuming `expectedLog` field is still there for the first test case.

	tests := []struct {
		name              string
		ip                string
		reason            string
		forgivable        ForgivableError
		errorCount        int // Number of times to call LogIPError
		whiteList         []string
		expectedBanned    bool
		expectedLogAction string // This will be used only if logs are expected
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
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFW := &MockIFirewall{}
			mockLogger := &MockILogger{}
			fw := New(tt.whiteList, mockFW, mockLogger, nil, tt.forgivable) // ipGeo is not used in LogIPError directly

			// Determine if logs are expected
			expectLogs := true
			for _, wlIP := range tt.whiteList {
				if wlIP == tt.ip {
					expectLogs = false
					break
				}
			}

			if expectLogs {
				mockLogger.Wg.Add(tt.errorCount)
			}

			for i := 0; i < tt.errorCount; i++ {
				fw.LogIPError(tt.ip, tt.reason)
			}

			if expectLogs {
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
