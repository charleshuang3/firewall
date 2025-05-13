package zerolog

import (
	"encoding/json"
	"time"

	zlog "github.com/rs/zerolog"

	"github.com/charleshuang3/firewall"
	"github.com/charleshuang3/firewall/ipgeo"
)

var _ firewall.ILogger = (*ZeroLog)(nil)

type ZeroLog struct {
	logger zlog.Logger
	level  zlog.Level
}

func New(logger zlog.Logger, level zlog.Level, service string) *ZeroLog {
	logger = logger.With().Str("service", service).Logger()
	return &ZeroLog{
		logger: logger,
		level:  level,
	}
}

func (z *ZeroLog) Log(ip string, jailUntil time.Time, reasons []string, action string, geo *ipgeo.IPGeo) {
	var b []byte
	if geo != nil {
		b, _ = json.Marshal(geo)
	}

	e := z.logger.WithLevel(z.level).
		Str("ip", ip).
		Time("jail_until", jailUntil).
		Strs("reasons", reasons).
		Str("action", action)

	if b != nil {
		e.RawJSON("geo", b)
	}

	e.Msg("") // emit the log
}
