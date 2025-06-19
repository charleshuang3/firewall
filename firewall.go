package firewall

import (
	"log"
	"time"

	"github.com/adrianbrad/queue"
	"golang.org/x/time/rate"

	"github.com/charleshuang3/firewall/ipgeo"
)

type IFirewall interface {
	BanIP(ip string, timeoutInMinute int)
}

type ILogger interface {
	Log(ip string, jailUntil time.Time, reasons []string, action string, geo *ipgeo.IPGeo)
}

type Firewall struct {
	whiteList []*ipMatcher

	ipGeo  *ipgeo.AutoUpdateMMIPGeo
	logger ILogger

	fw IFirewall

	forgivable ForgivableError
	errorCount map[string]*errorCounter

	banCh   chan ban
	countCh chan countingError
}

type ban struct {
	ip              string
	timeoutInMinute int
	reasons         []string
}

type countingError struct {
	ip     string
	reason string
}

// ForgivableError represent to the maxium error we can forgive per ip in
// the given Durations.
type ForgivableError struct {
	Duration    time.Duration
	Count       int
	BanInMinute int
}

type errorCounter struct {
	rateLimiter rate.Limiter
	reasons     *queue.Linked[string]
	bannedUntil time.Time
}

func New(whiteList []string,
	fw IFirewall,
	logger ILogger,
	ipGeo *ipgeo.AutoUpdateMMIPGeo,
	forgivable ForgivableError,
) *Firewall {
	if logger == nil {
		log.Fatalln("firewall logger is nil")
	}

	f := &Firewall{
		whiteList:  []*ipMatcher{},
		fw:         fw,
		logger:     logger,
		forgivable: forgivable,
		errorCount: map[string]*errorCounter{},
		banCh:      make(chan ban),
		countCh:    make(chan countingError),
	}

	for _, it := range whiteList {
		f.whiteList = append(f.whiteList, newIPMatcher(it))
	}

	go f.loop()

	return f
}

func (s *Firewall) loop() {
	for {
		select {
		case b := <-s.banCh:
			if s.inWhitelist(b.ip) {
				// IP is whitelisted, do not log
				continue
			}
			s.doBanIP(&b)
		case c := <-s.countCh:
			if s.inWhitelist(c.ip) {
				// IP is whitelisted, do not log
				continue
			}
			s.doCountError(&c)
		}
	}
}

func (s *Firewall) inWhitelist(ip string) bool {
	for _, it := range s.whiteList {
		if it.match(parseIP(ip)) {
			return true
		}
	}
	return false
}

func (s *Firewall) doBanIP(b *ban) {
	if s.fw != nil {
		s.fw.BanIP(b.ip, b.timeoutInMinute)
	}

	var geo *ipgeo.IPGeo
	if s.ipGeo != nil {
		geo = s.ipGeo.GetIPGeo(b.ip)
	}
	jailUntil := time.Now().Add(time.Duration(b.timeoutInMinute) * time.Minute)
	s.logger.Log(b.ip, jailUntil, b.reasons, "ban", geo)
}

// BanIP imimmediately
func (s *Firewall) BanIP(ip string, timeoutInMinute int, reason string) {
	s.banCh <- ban{
		ip:              ip,
		timeoutInMinute: timeoutInMinute,
		reasons:         []string{reason},
	}
}

func (s *Firewall) doCountError(c *countingError) {
	ec, ok := s.errorCount[c.ip]
	if !ok {
		ec = &errorCounter{
			rateLimiter: *rate.NewLimiter(rate.Every(s.forgivable.Duration), s.forgivable.Count),
			reasons:     queue.NewLinked([]string{}),
		}
		s.errorCount[c.ip] = ec
	}

	if ec.bannedUntil.After(time.Now()) {
		s.logger.Log(c.ip, time.Time{}, []string{c.reason}, "banned", nil)
		return
	}

	ec.reasons.Offer(c.reason)
	for ec.reasons.Size() > s.forgivable.Count {
		ec.reasons.Get()
	}

	if ec.rateLimiter.Allow() {
		s.logger.Log(c.ip, time.Time{}, []string{c.reason}, "count error", nil)
		return
	}

	// record this ip is banned until time, no need to handle doCountError until then.
	ec.bannedUntil = time.Now().Add(time.Duration(s.forgivable.BanInMinute) * time.Minute)

	reasons := []string{}
	for ec.reasons.Size() > 0 {
		r, _ := ec.reasons.Get()
		reasons = append(reasons, r)
	}

	s.doBanIP(&ban{
		ip:              c.ip,
		timeoutInMinute: s.forgivable.BanInMinute,
		reasons:         reasons,
	})
}

// LogIPError counts an error happens on request from given ip, ban the ip
// reach to the threshold.
func (s *Firewall) LogIPError(ip string, reason string) {
	s.countCh <- countingError{
		ip:     ip,
		reason: reason,
	}
}
