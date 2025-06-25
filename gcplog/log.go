package gcplog

import (
	"context"
	"time"

	"cloud.google.com/go/logging"
	"google.golang.org/api/option"

	"github.com/charleshuang3/firewall"
	"github.com/charleshuang3/firewall/ipgeo"
)

var _ firewall.ILogger = (*Logger)(nil)

type Logger struct {
	client *logging.Client
	logger *logging.Logger
}

func New(authFile, projectID, service string) (*Logger, error) {
	ctx := context.Background()
	opt := option.WithCredentialsFile(authFile)
	client, err := logging.NewClient(ctx, projectID, opt)
	if err != nil {
		return nil, err
	}

	return &Logger{
		client: client,
		logger: client.Logger(service),
	}, nil
}

// Close Should be call in grateful shutdown
func (s *Logger) Close() {
	s.client.Close()
}

type logEntry struct {
	IP        string       `json:"ip"`
	JailUntil string       `json:"jail_until,omitempty"`
	Reasons   []string     `json:"reasons"`
	Action    string       `json:"action"`
	Geo       *ipgeo.IPGeo `json:"geo"`
}

func (s *Logger) Log(ip string, jailUntil time.Time, reasons []string, action string, geo *ipgeo.IPGeo) {
	e := &logEntry{
		IP:      ip,
		Reasons: reasons,
		Action:  action,
		Geo:     geo,
	}
	if !jailUntil.IsZero() {
		e.JailUntil = jailUntil.Format(time.RFC3339)
	}

	s.logger.Log(logging.Entry{Payload: e})
}
